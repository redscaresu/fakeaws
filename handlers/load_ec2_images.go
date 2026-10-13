package handlers

// load_ec2_images.go — the DescribeImages loader. A public image (an
// Amazon one, with its numeric owner and its alias) loads under the
// loaded account, which sees it; it resolves the image a loaded instance
// or al2023 parameter names.

import (
	"cmp"

	"github.com/redscaresu/fakeaws/repository"
)

func init() {
	registerLoader(loader{key: LoadKey{"ec2", "DescribeImages"}, table: "ec2_amis",
		typ: "image", notFound: []string{"InvalidAMIID.NotFound"},
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeImages, render: renderImages})
}

// decodeImages loads each image with its owner and alias as recorded,
// and the fields aws_ami reads (repository.EC2AMIRecorded).
func decodeImages(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeImagesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.ImagesSet))
	for i, x := range body.ImagesSet {
		recorded := *cmp.Or(x.EC2AMIRecorded, &repository.EC2AMIRecorded{})
		recorded.OwnerAlias = x.ImageOwnerAlias
		ami := &repository.EC2AMI{ID: x.ImageId, Name: x.Name, OwnerID: x.OwnerId, VirtualizationType: x.VirtualizationType,
			RootDeviceName: x.RootDeviceName, Region: env.Region, EC2AMIRecorded: &recorded}
		items[i] = loadItem{loadRef: loadRef{"image", x.ImageId}, Path: "imagesSet/item", Index: i,
			write: func(tx *repository.LoadTx) error { return tx.PutAMI(env.Account, ami) }}
	}
	return items, nil
}

func renderImages(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeImagesResult{ImagesSet: []ec2ImageXML{}}
	for _, id := range ids {
		ami, err := tx.AMI(id)
		if err != nil {
			return nil, err
		}
		out.ImagesSet = append(out.ImagesSet, ec2AMIToXML(ami))
	}
	return ec2Body("DescribeImages", &out), nil
}
